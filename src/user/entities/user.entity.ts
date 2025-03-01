import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  OneToMany,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn,
} from 'typeorm';
import { Project } from '../../project/entities/project.entity';
import { Post } from '../../post/entities/post.entity';
import { Like } from '../../like/entities/like.entity';
import { Comment } from '../../comment/entities/comment.entity';
import { Bookmark } from '../../bookmark/entities/bookmark.entity';
import { Follow } from '../../follow/entities/follow.entity';

@Entity('users')
export class User {
  // 1) Switch from UUID to auto-increment integer
  @PrimaryGeneratedColumn()
  id: number; // This will be an INT by default

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column()
  username: string;

  @Column({ nullable: true })
  profilePicture: string;

  @Column({ nullable: true })
  bio: string;

  @Column({
    type: 'enum',
    enum: ['Free', 'Pro'],
    default: 'Free',
  })
  planType: string;

  @Column({ default: 0 })
  renderCredits: number;

  // Foreign key relationships
  @OneToMany(() => Project, (project) => project.user)
  projects: Project[];

  @OneToMany(() => Post, (post) => post.user)
  posts: Post[];

  @OneToMany(() => Like, (like) => like.user)
  likes: Like[];

  @OneToMany(() => Comment, (comment) => comment.user)
  comments: Comment[];

  @OneToMany(() => Bookmark, (bookmark) => bookmark.user)
  bookmarks: Bookmark[];

  @OneToMany(() => Follow, (follow) => follow.follower)
  following: Follow[];

  @OneToMany(() => Follow, (follow) => follow.following)
  followers: Follow[];

  @Column({ nullable: true })
  refreshToken?: string; // Storing hashed refresh token

  // 2) Auto-manage creation, update, and soft-delete timestamps
  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  /**
   * When you add @DeleteDateColumn, TypeORM can use "soft delete" 
   * (the record is marked deleted but not physically removed).
   * If you call repository.softRemove(...), it sets the deletedAt value.
   */
  @DeleteDateColumn()
  deletedAt?: Date;
}
