import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, OneToMany } from 'typeorm';
import { User } from '../../user/entities/user.entity';
import { Project } from '../../project/entities/project.entity';
import { Like } from '../../like/entities/like.entity';
import { Comment } from '../../comment/entities/comment.entity';
import { Bookmark } from '../../bookmark/entities/bookmark.entity';

@Entity('posts')
export class Post {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => User, (user) => user.posts, { onDelete: 'CASCADE' })
  user: User;

  @ManyToOne(() => Project, (project) => project.posts, { nullable: true })
  project: Project;

  @Column()
  imageUrl: string;

  @Column({ nullable: true })
  description: string;

  @Column({ default: 0 })
  likeCount: number;

  @Column({ default: 0 })
  commentCount: number;

  @Column({ default: false })
  isTrending: boolean;

  @OneToMany(() => Like, (like) => like.post)
  likes: Like[];

  @OneToMany(() => Comment, (comment) => comment.post)
  comments: Comment[];

  @OneToMany(() => Bookmark, (bookmark) => bookmark.post)
  bookmarks: Bookmark[];

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;
}
