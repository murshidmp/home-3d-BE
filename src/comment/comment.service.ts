import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Comment } from './entities/comment.entity';
import { Post } from '../post/entities/post.entity';
import { User } from '../user/entities/user.entity';
import { plainToClass } from 'class-transformer';
import { CommentResponseDto } from './dto/comment-response.dto';

@Injectable()
export class CommentService {
  constructor(
    @InjectRepository(Comment) private readonly commentRepository: Repository<Comment>,
    @InjectRepository(Post) private readonly postRepository: Repository<Post>,
    @InjectRepository(User) private readonly userRepository: Repository<User>,
  ) {}

  async createComment(userId: number, postId: number, content: string): Promise<CommentResponseDto> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    const post = await this.postRepository.findOne({ where: { id: postId } });
    if (!user || !post) throw new NotFoundException('User or Post not found');

    const comment = this.commentRepository.create({ user, post, content });
    const savedComment = await this.commentRepository.save(comment);

    post.commentCount += 1;
    await this.postRepository.save(post);

    return this.mapCommentToDto(savedComment);
  }

  async deleteComment(userId: number, commentId: number): Promise<void> {
    const comment = await this.commentRepository.findOne({ where: { id: commentId }, relations: ['user', 'post'] });
    if (!comment) throw new NotFoundException('Comment not found');
    if (comment.user.id !== userId) throw new ForbiddenException('You do not own this comment');

    await this.commentRepository.remove(comment);

    comment.post.commentCount -= 1;
    await this.postRepository.save(comment.post);
  }

  async getCommentsForPost(postId: number): Promise<CommentResponseDto[]> {
    const comments = await this.commentRepository.find({ where: { post: { id: postId } }, relations: ['user'] });
    return comments.map(comment => this.mapCommentToDto(comment));
  }

  private mapCommentToDto(comment: Comment): CommentResponseDto {
    return plainToClass(CommentResponseDto, comment, { excludeExtraneousValues: true });
  }
}