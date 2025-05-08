import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Bookmark } from './entities/bookmark.entity';
import { User } from '../user/entities/user.entity';
import { Post } from '../post/entities/post.entity';
import { plainToClass } from 'class-transformer';
import { BookmarkResponseDto } from './dto/bookmark-response.dto';

@Injectable()
export class BookmarkService {
  constructor(
    @InjectRepository(Bookmark)
    private readonly bookmarkRepository: Repository<Bookmark>,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Post)
    private readonly postRepository: Repository<Post>,
  ) {}

  async bookmarkPost(userId: number, postId: number): Promise<BookmarkResponseDto> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    const post = await this.postRepository.findOne({ where: { id: postId } });
    if (!user || !post) throw new NotFoundException('User or Post not found');

    const existingBookmark = await this.bookmarkRepository.findOne({
      where: { user: { id: userId }, post: { id: postId } },
    });
    if (existingBookmark) throw new ConflictException('Bookmark already exists');

    const bookmark = this.bookmarkRepository.create({ user, post });
    const savedBookmark = await this.bookmarkRepository.save(bookmark);
    return this.mapBookmarkToDto(savedBookmark);
  }

  async removeBookmark(userId: number, postId: number): Promise<void> {
    const bookmark = await this.bookmarkRepository.findOne({
      where: { user: { id: userId }, post: { id: postId } },
    });
    if (!bookmark) throw new NotFoundException('Bookmark not found');
    await this.bookmarkRepository.remove(bookmark);
  }

  async getBookmarksForUser(userId: number): Promise<BookmarkResponseDto[]> {
    const bookmarks = await this.bookmarkRepository.find({
      where: { user: { id: userId } },
      relations: ['post', 'user'],
    });
    return bookmarks.map(bookmark => this.mapBookmarkToDto(bookmark));
  }

  private mapBookmarkToDto(bookmark: Bookmark): BookmarkResponseDto {
    return plainToClass(BookmarkResponseDto, bookmark, {
      excludeExtraneousValues: true,
    });
  }
}